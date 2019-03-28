/*************************************************
* Copyright (c) Rennie deGraaf, 2007.  All rights reserved.
* $Id$
* 
* This file is part of LibWheel.
**************************************************/

/**
* @file auto_array.hpp
* @author Rennie deGraaf 
* @date 2007/05/28
*
* Provides auto_array and related classes, an analogue to std::auto_ptr for 
* arrays.
*/

/* based on Daryle Walker's post to comp.std.c++ on Mar 11, 2005 and the
GNU implementation of std::auto_ptr */

#ifndef LIBWHEEL_AUTO_ARRAY_HPP
    #define LIBWHEEL_AUTO_ARRAY_HPP

    #include <cstddef>      // for size_t

    namespace LibWheel
    {
        /**
        * A simple smart pointer for arrays that provides strict ownership 
        * semantics in the manner of std::auto_ptr.  Despite what the C++ 
        * standard guys will tell you, it \b isn't always possible to use 
        * std::vector in place of an array.  For intance, you may need to call 
        * a C or external library API that requires an array.  This class 
        * provides automatic destruction in the manner of std::auto_ptr for true 
        * arrays.
        */
        template <typename T>
        class auto_array
        {
          private:
            /**
            * A wrapper class to provide auto_array with reference semantics.
            * This allows an auto_array to be assigned or constructed from the
            * result of a function that returns an auto_array by value.  This
            * allows constructs such as 
            * @code
            *   auto_array<Derived> func_returning_auto_ptr(....);
            *   ...
            *   auto_array<Base> ptr = func_returning_auto_ptr(....);
            * @endcode
            */
            struct auto_array_ref
            {
                T* ptr; ///< A pointer to a dynamically-allocated array.
                explicit auto_array_ref(T* p);
            };
            
            T* ptr; ///< The array owned by this auto_array.
            
          public:
            typedef T element_type; ///< The type of the contained array.

            explicit auto_array(element_type* p = 0) throw();
            auto_array(auto_array<T>& a) throw() ;

            auto_array<element_type>& operator=(auto_array<T>& a) throw();
            auto_array<element_type>& operator=(auto_array_ref ref) throw();

            ~auto_array() throw();
            
            element_type& operator[] (std::size_t i) const throw();
            element_type* get() const throw();
            element_type* release() throw();
            void reset(element_type* p = 0) throw();
            
            auto_array(auto_array_ref ref) throw();
            operator auto_array_ref() throw();
        };
        

        /**
        * Constructs an auto_array from a pointer to a dynamically allocated 
        * array.  The constructed auto_array will own the array pointed to by 
        * \a p.
        * @param p A pointer to a dynamically-allocated array.
        * @warning Constructing an auto_array from a pointer to a single object,
        *       statically-allocated array, or anything else not allocated with
        *       new[] results in undefined behaviour.
        */
        template <typename T>
        auto_array<T>::auto_array(element_type* p) throw()
        : ptr(p) 
        {}


        /**
        * Constructs an auto_array from another auto_array.  The constructed
        * auto_array will own the array originally owned by \a a.
        * @param a Another auto_array of the same type.
        * @sideeffect \a a will loose ownership of its array.
        */
        template <typename T>
        auto_array<T>::auto_array(auto_array<T>& a) throw() 
        : ptr(a.release()) 
        {}


        /**
        * Assign one auto_array to another. The array owned by this auto_array 
        * will be deleted, and this auto_array will take ownership of the array 
        * originally owned by \a a.
        * @param a Another auto_array of the same type.
        * @sideeffect \a a will loose ownership of its array.
        */
        template <typename T>
        auto_array<T>&
        auto_array<T>::operator=(auto_array<T>& a) throw()
        {
            reset(a.release());
            return *this;
        }


        /**
        * Destructor for auto_array.  Frees the memory held by this auto_array.
        */
        template <typename T>
        auto_array<T>::~auto_array() throw()
        {
            delete[] ptr;
        }


        /**
        * Index operator for auto_array.  Retrieves an element from this 
        * auto_array.
        * @param i The index of the element to retrieve.
        * @return The element of the currently-owned array at index \a i.
        * @warning No bounds checks are made.  Supplying a value of \a i outside
        *       of the bounds of the currently-owned array results in undefined 
        *       behaviour.
        */
        template <typename T>
        T&
        auto_array<T>::operator[] (std::size_t i) const throw()
        {
            return ptr[i];
        }


        /**
        * Retrieves a pointer to the currently-owned array.  Ownership is not
        * changed.
        * @return A pointer to the currently-owned array.
        */
        template <typename T>
        T*
        auto_array<T>::get() const throw()
        {
            return ptr;
        }


        /**
        * Releases ownership of the currently-owned array.  The caller is then
        * responsible for managing it.
        * @return A pointer to the currently-owned array.
        */
        template <typename T>
        T*
        auto_array<T>::release() throw()
        {
            element_type* tmp = ptr;
            ptr = 0;
            return tmp;
        }


        /**
        * Frees and drops ownership of the currently-owned array, and takes 
        * ownership of a new array.
        * @param p A pointer to a dynamically-allocated array.
        * @warning Assigning ownership of a single object, statically-allocated 
        *       array, or anything else not allocated with new[] to an 
        *       auto_arrayresults in undefined behaviour.
        */
        template <typename T>
        void
        auto_array<T>::reset(element_type* p) throw()
        {
            if (p != ptr)
            {
                delete[] ptr;
                ptr = p;
            }
        }


        /**
        * Constructs an auto_array from an auto_array_ref.  The constructed 
        * auto_array owns the array pointed to by \a ref.
        * @param ref An auto_array_ref of the same type.
        */
        template <typename T>
        auto_array<T>::auto_array(auto_array_ref ref) throw()
        : ptr(ref.ptr)
        {}


        /**
        * Assign an auto_array_ref to an auto_array.  The array owned by this 
        * auto_array will be deleted, and this auto_array will take ownersnip of
        * the array pointed to by \a ref.
        * @param ref An auto_array_ref of the same type.
        */
        template <typename T>
        auto_array<T>&
        auto_array<T>::operator=(auto_array_ref ref) throw()
        {
            reset(ref.ptr);
            return *this;
        }


        /**
        * Converts an auto_array into an auto_array_ref.  Ownership of the 
        * currently-owned array is dropped.
        * @return An auto_array_ref containing a pointer to the array formerly 
        *       owned by this auto_array.
        */
        template <typename T>
        auto_array<T>::operator auto_array_ref() throw()
        {
            return auto_array_ref(this->release());
        }

        
        /**
        * Constructs an auto_array_ref from a dynamically-allocated array.
        * @param p A dynamically-allocated array.
        */
        template <typename T>
        auto_array<T>::auto_array_ref::auto_array_ref(T* p)
        : ptr(p)
        {}

    } // namespace LibWheel

#endif /* LIBWHEEL_AUTO_ARRAY_HPP */
